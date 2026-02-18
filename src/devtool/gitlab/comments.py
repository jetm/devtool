"""devtool comments — fetch unresolved MR discussions."""

import logging
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from devtool.gitlab import connect_gitlab, get_gitlab_token, parse_mr_url

logger = logging.getLogger(__name__)
console = Console()


def fetch_unresolved_discussions(gl, project_id: int, mr_iid: int) -> tuple[list[Any], str, str]:
    """Fetch all unresolved discussion threads from a merge request."""
    logger.info(f"Fetching merge request {mr_iid} from project {project_id}")
    project = gl.projects.get(project_id)
    mr = project.mergerequests.get(mr_iid)

    logger.info(f"Project: {project.name_with_namespace}")
    logger.info(f"Merge Request: {mr.title}")
    logger.info("Fetching all discussions")
    discussions = mr.discussions.list(get_all=True)
    logger.debug(f"Total discussions found: {len(discussions)}")

    unresolved = []
    for discussion in discussions:
        # Skip individual notes (standalone comments, not discussion threads)
        if discussion.attributes.get("individual_note", False):
            continue

        notes = discussion.attributes.get("notes", [])
        if not notes:
            continue

        # Check if any note in the thread is resolvable and unresolved
        has_unresolved_note = False
        for note in notes:
            if note.get("resolvable", False) and not note.get("resolved", False):
                has_unresolved_note = True
                break

        if has_unresolved_note:
            unresolved.append(discussion)

    logger.info(f"Found {len(unresolved)} unresolved discussion threads")
    return unresolved, project.name_with_namespace, mr.title


def get_code_context(
    gl,
    project_id: int,
    mr_iid: int,
    file_path: str,
    line_number: int | None,
    context_lines: int = 3,
    is_old_side: bool = False,
) -> dict[str, Any]:
    """Extract code context from MR diff around a specific line."""
    if not file_path or line_number is None:
        return {"before_lines": [], "target_line": None, "after_lines": [], "line_numbers": []}

    try:
        project = gl.projects.get(project_id)
        mr = project.mergerequests.get(mr_iid)
        changes = mr.changes()

        # Find the file in changes
        target_change = None
        for change in changes.get("changes", []):
            if change.get("new_path") == file_path or change.get("old_path") == file_path:
                target_change = change
                break

        if not target_change:
            logger.debug(f"File {file_path} not found in MR changes")
            return {"before_lines": [], "target_line": None, "after_lines": [], "line_numbers": []}

        diff_content = target_change.get("diff", "")
        if not diff_content:
            return {"before_lines": [], "target_line": None, "after_lines": [], "line_numbers": []}

        # Parse unified diff format
        lines = diff_content.split("\n")
        old_line_num = 0
        new_line_num = 0
        collected_old_lines = []
        collected_new_lines = []

        for line in lines:
            if line.startswith("@@"):
                parts = line.split()
                for part in parts:
                    if part.startswith("-"):
                        old_start = part[1:].split(",")[0]
                        old_line_num = int(old_start) - 1
                    elif part.startswith("+"):
                        new_start = part[1:].split(",")[0]
                        new_line_num = int(new_start) - 1
                continue

            if line.startswith("-"):
                old_line_num += 1
                collected_old_lines.append((old_line_num, line[1:]))
            elif line.startswith("+"):
                new_line_num += 1
                collected_new_lines.append((new_line_num, line[1:]))
            elif line.startswith(" "):
                old_line_num += 1
                new_line_num += 1
                collected_old_lines.append((old_line_num, line[1:]))
                collected_new_lines.append((new_line_num, line[1:]))

        collected_lines = collected_old_lines if is_old_side else collected_new_lines

        # Find target line and extract context
        target_idx = None
        for idx, (num, _) in enumerate(collected_lines):
            if num == line_number:
                target_idx = idx
                break

        if target_idx is None:
            logger.debug(f"Line {line_number} not found in diff")
            return {"before_lines": [], "target_line": None, "after_lines": [], "line_numbers": []}

        start_idx = max(0, target_idx - context_lines)
        end_idx = min(len(collected_lines), target_idx + context_lines + 1)

        before_lines = [line for _, line in collected_lines[start_idx:target_idx]]
        target_line = collected_lines[target_idx][1]
        after_lines = [line for _, line in collected_lines[target_idx + 1 : end_idx]]
        line_numbers = [num for num, _ in collected_lines[start_idx:end_idx]]

        return {
            "before_lines": before_lines,
            "target_line": target_line,
            "after_lines": after_lines,
            "line_numbers": line_numbers,
        }

    except Exception as e:
        logger.debug(f"Error extracting code context: {e}")
        return {"before_lines": [], "target_line": None, "after_lines": [], "line_numbers": []}


def format_output(
    project_id: int,
    mr_iid: int,
    unresolved_threads: list[Any],
    gl,
    project_name: str,
    mr_title: str,
) -> str:
    """Format unresolved discussions into plain text output for LLM consumption."""
    separator = "=" * 80
    output_lines = []

    # Header
    output_lines.append(separator)
    output_lines.append("GITLAB MERGE REQUEST UNRESOLVED COMMENTS")
    output_lines.append(separator)
    output_lines.append(f"Project: {project_name} (ID: {project_id})")
    output_lines.append(f"Merge Request: {mr_title} (IID: {mr_iid})")
    output_lines.append(f"Unresolved Threads: {len(unresolved_threads)}")
    output_lines.append(separator)
    output_lines.append("")

    for thread_num, discussion in enumerate(unresolved_threads, 1):
        notes = discussion.attributes.get("notes", [])
        if not notes:
            continue

        first_note = notes[0]
        position = first_note.get("position", {})

        new_line = position.get("new_line") if position else None
        old_line = position.get("old_line") if position else None

        if new_line is not None:
            line_number = new_line
            file_path = position.get("new_path")
            is_old_side = False
        elif old_line is not None:
            line_number = old_line
            file_path = position.get("old_path")
            is_old_side = True
        else:
            line_number = None
            file_path = None
            is_old_side = False

        output_lines.append(f"THREAD #{thread_num}")
        output_lines.append("-" * 80)

        if file_path:
            output_lines.append(f"File: {file_path}")
            if line_number:
                output_lines.append(f"Line: {line_number}")
        else:
            output_lines.append("Location: General comment (no specific file/line)")
        output_lines.append("")

        if file_path and line_number:
            context = get_code_context(gl, project_id, mr_iid, file_path, line_number, is_old_side=is_old_side)
            if context["target_line"] is not None:
                output_lines.append("Code Context:")
                output_lines.append("-" * 80)

                all_lines = context["before_lines"] + [context["target_line"]] + context["after_lines"]
                line_nums = context["line_numbers"]

                for i, (num, line) in enumerate(zip(line_nums, all_lines, strict=True)):
                    marker = ">" if i == len(context["before_lines"]) else " "
                    output_lines.append(f"  {marker} {num:4d} | {line}")

                output_lines.append("-" * 80)
                output_lines.append("")

        output_lines.append("Comments:")
        output_lines.append("-" * 80)
        for note in notes:
            author = note.get("author", {}).get("username", "unknown")
            body = note.get("body", "")
            output_lines.append(f"@{author}:")
            for line in body.split("\n"):
                output_lines.append(f"  {line}")
            output_lines.append("")

        output_lines.append(separator)
        output_lines.append("")

    return "\n".join(output_lines)


@click.command()
@click.argument("mr_url", required=False, default=None)
@click.option("--project-id", type=int, help="GitLab project ID (numeric)")
@click.option("--project", type=str, help="GitLab project path (e.g., group/project)")
@click.option("--mr-id", type=int, help="Merge request IID")
@click.option("--token", type=str, default=None, help="GitLab token (or set GITLAB_TOKEN env var)")
@click.option("--output", type=str, help="Output file path (default: stdout)")
def comments(
    mr_url: str | None,
    project_id: int | None,
    project: str | None,
    mr_id: int | None,
    token: str | None,
    output: str | None,
) -> None:
    """Fetch unresolved comments from a GitLab merge request.

    Provide MR_URL, or use --project/--project-id with --mr-id.
    """
    from gitlab import GitlabAuthenticationError, GitlabGetError

    # Validate and resolve arguments
    if mr_url:
        if project_id or project or mr_id:
            raise click.ClickException("MR_URL cannot be used with --project-id, --project, or --mr-id")
        parsed = parse_mr_url(mr_url)
        if not parsed:
            raise click.ClickException(
                "Invalid GitLab MR URL format. Expected: https://gitlab.com/{project}/-/merge_requests/{id}"
            )
        project_identifier, resolved_mr_id = parsed
    else:
        if not (project_id or project):
            raise click.ClickException("Provide MR_URL, or use --project-id/--project with --mr-id")
        if not mr_id:
            raise click.ClickException("--mr-id is required when not using MR_URL")
        project_identifier = project_id if project_id else project
        resolved_mr_id = mr_id

    try:
        resolved_token = get_gitlab_token(token)
        gl = connect_gitlab(resolved_token)

        # Resolve project
        resolved_project = gl.projects.get(project_identifier)
        resolved_project_id = resolved_project.id

        # Fetch unresolved discussions
        unresolved_threads, project_name, mr_title = fetch_unresolved_discussions(
            gl, resolved_project_id, resolved_mr_id
        )

        if not unresolved_threads:
            console.print("[yellow]No unresolved discussion threads found[/yellow]")
            sys.exit(0)

        # Format and output
        formatted = format_output(resolved_project_id, resolved_mr_id, unresolved_threads, gl, project_name, mr_title)
        if output:
            Path(output).write_text(formatted)
            logger.info(f"Output written to {output}")
        else:
            print(formatted)

        sys.exit(0)

    except GitlabAuthenticationError as e:
        logger.error(f"Authentication failed: {e}")
        sys.exit(1)
    except GitlabGetError as e:
        logger.error(f"Failed to fetch data from GitLab: {e}")
        sys.exit(1)
    except click.ClickException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
