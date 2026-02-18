"""devtool switch-main — auto-detect and switch to the main branch."""

import logging

import click

logger = logging.getLogger(__name__)


@click.command()
@click.argument("branch", required=False, default=None)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose/debug logging")
@click.pass_context
def switch_main(ctx: click.Context, branch: str | None, verbose: bool) -> None:
    """Switch to the main branch (auto-detected or specified).

    If BRANCH is given, switch to it directly and cache it.
    Otherwise, auto-detect using cached config, origin/HEAD, or common branch names.

    Uncommitted changes are automatically stashed and restored after switching.
    """
    import git

    from devtool.common.console import setup_logging

    setup_logging(verbose=verbose)

    from datetime import datetime

    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table

    console = Console()

    # --- helpers (closed over console) ---

    def get_repo() -> git.Repo | None:
        """Find and return the git repository, or None if not in a repo."""
        try:
            return git.Repo(search_parent_directories=True)
        except git.exc.InvalidGitRepositoryError:
            console.print(
                Panel(
                    "Not in a git repository.\n\nPlease run this command from within a git repository.",
                    title="Error",
                    border_style="red",
                )
            )
            return None

    def detect_main_branch(repo: git.Repo) -> str | None:
        """Detect the main branch using multiple strategies.

        Priority:
        1. Cached config (branch-switch.name)
        2. origin/HEAD symbolic reference
        3. Common branch names (stage, main, master, trunk, develop)
        """
        # Priority 1: Check cached config
        try:
            cached_branch = repo.config_reader().get_value("branch-switch", "name", default=None)
            if cached_branch:
                local_exists = cached_branch in [h.name for h in repo.heads]
                remote_exists = False
                try:
                    remote_exists = cached_branch in [ref.remote_head for ref in repo.remotes.origin.refs]
                except AttributeError, IndexError:
                    pass

                if local_exists or remote_exists:
                    console.print(f"[blue]i[/blue] Using cached main branch: [bold]{cached_branch}[/bold]")
                    logger.debug("Cache hit for branch-switch.name: %s", cached_branch)
                    return cached_branch
                else:
                    console.print(f"[yellow]![/yellow] Cached branch '{cached_branch}' no longer exists, detecting...")
        except Exception:
            pass

        candidates: list[str] = []

        # Priority 2: Check origin/HEAD
        try:
            origin_head = repo.remotes.origin.refs.HEAD
            if origin_head.is_valid():
                target = origin_head.reference.name
                if "/" in target:
                    branch_name = target.split("/")[-1]
                    candidates.append(branch_name)
                    logger.debug("origin/HEAD points to: %s", branch_name)
        except AttributeError, TypeError, KeyError:
            pass

        # Priority 3: Check common branch names
        common_names = ["stage", "main", "master", "trunk", "develop"]
        local_branches = [h.name for h in repo.heads]

        remote_branches: list[str] = []
        try:
            remote_branches = [ref.remote_head for ref in repo.remotes.origin.refs]
        except AttributeError, IndexError:
            pass

        for name in common_names:
            if name in local_branches or name in remote_branches:
                if name not in candidates:
                    candidates.append(name)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_candidates: list[str] = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique_candidates.append(c)

        logger.debug("Candidates after dedup: %s", unique_candidates)

        if not unique_candidates:
            console.print(
                Panel(
                    "Could not detect the main branch.\n\n"
                    "Please set it manually:\n"
                    "  git config branch-switch.name <branch-name>",
                    title="Error",
                    border_style="red",
                )
            )
            return None

        if len(unique_candidates) == 1:
            selected = unique_candidates[0]
            console.print(f"[green]✓[/green] Detected main branch: [bold]{selected}[/bold]")
            with repo.config_writer() as config:
                config.set_value("branch-switch", "name", selected)
            return selected

        # Multiple candidates — prompt user
        console.print("[yellow]![/yellow] Multiple potential main branches found. Please select one:")

        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=3)
        table.add_column("Branch", style="cyan")

        for i, b in enumerate(unique_candidates, 1):
            table.add_row(str(i), b)

        console.print(table)

        choices = [str(i) for i in range(1, len(unique_candidates) + 1)]
        choice = Prompt.ask("Select branch number", choices=choices, default="1")

        selected = unique_candidates[int(choice) - 1]
        console.print(f"[green]✓[/green] Selected: [bold]{selected}[/bold]")

        with repo.config_writer() as config:
            config.set_value("branch-switch", "name", selected)

        return selected

    def auto_stash(repo: git.Repo) -> str | None:
        """Stash changes if the working tree is dirty.

        Returns the stash reference if created, None otherwise.
        """
        if not repo.is_dirty(untracked_files=True):
            return None

        message = f"auto-switch-main {datetime.now().isoformat()}"
        console.print(f"[yellow]![/yellow] Stashing changes: {message}")

        try:
            repo.git.stash("push", "--include-untracked", "-m", message)

            stash_list = repo.git.stash("list")
            if stash_list:
                first_line = stash_list.split("\n")[0]
                stash_ref = first_line.split(":")[0]  # e.g. "stash@{0}"
                console.print(f"[green]✓[/green] Created stash: {stash_ref}")
                return stash_ref
        except git.exc.GitCommandError as e:
            console.print(
                Panel(
                    f"Failed to stash changes:\n{e}",
                    title="Stash Error",
                    border_style="red",
                )
            )
            raise

        return None

    def restore_stash(repo: git.Repo, stash_ref: str) -> None:
        """Restore a previously created stash."""
        try:
            repo.git.stash("pop", "--index", stash_ref)
            console.print(f"[green]✓[/green] Restored stash: {stash_ref}")
        except git.exc.GitCommandError as e:
            console.print(
                Panel(
                    f"Failed to restore stash automatically:\n{e}\n\n"
                    f"Your changes are still saved in: {stash_ref}\n"
                    "You can restore them manually with:\n"
                    f"  git stash pop {stash_ref}",
                    title="Stash Restore Warning",
                    border_style="yellow",
                )
            )

    def switch_to_branch(repo: git.Repo, branch_name: str) -> None:
        """Switch to the specified branch, creating a tracking branch if needed."""
        local_branches = {h.name: h for h in repo.heads}
        if branch_name in local_branches:
            local_branches[branch_name].checkout()
            console.print(f"[green]✓[/green] Switched to local branch: [bold]{branch_name}[/bold]")
            return

        try:
            remote_refs = {ref.remote_head: ref for ref in repo.remotes.origin.refs}
            if branch_name in remote_refs:
                remote_ref = remote_refs[branch_name]
                local_branch = repo.create_head(branch_name, remote_ref)
                local_branch.set_tracking_branch(remote_ref)
                local_branch.checkout()
                console.print(f"[green]✓[/green] Created and switched to tracking branch: [bold]{branch_name}[/bold]")
                return
        except AttributeError, IndexError:
            pass

        console.print(
            Panel(
                f"Branch '{branch_name}' does not exist locally or on origin.\n\n"
                "Please check the branch name or set a different main branch:\n"
                "  git config branch-switch.name <branch-name>",
                title="Branch Not Found",
                border_style="red",
            )
        )
        raise git.exc.GitCommandError("checkout", f"Branch '{branch_name}' not found")

    def cache_branch(repo: git.Repo, name: str) -> None:
        """Write *name* into the branch-switch.name git config key."""
        with repo.config_writer() as config:
            config.set_value("branch-switch", "name", name)
        logger.debug("Cached branch-switch.name = %s", name)

    # --- main flow ---

    repo = get_repo()
    if repo is None:
        raise SystemExit(1)

    if branch is not None:
        # Explicit branch supplied — skip detection, cache it
        branch_name = branch
        console.print(f"[blue]i[/blue] Using specified branch: [bold]{branch_name}[/bold]")
        cache_branch(repo, branch_name)
    else:
        branch_name = detect_main_branch(repo)
        if branch_name is None:
            raise SystemExit(1)

    # Already on target?
    try:
        current_branch = repo.active_branch.name
        if current_branch == branch_name:
            console.print(f"[blue]i[/blue] Already on branch: [bold]{branch_name}[/bold]")
            return
    except TypeError:
        # Detached HEAD state — proceed with switch
        pass

    # Auto-stash
    stash_ref = None
    try:
        stash_ref = auto_stash(repo)
    except git.exc.GitCommandError:
        raise SystemExit(1) from None

    # Switch, then restore stash regardless of outcome
    try:
        switch_to_branch(repo, branch_name)
    except git.exc.GitCommandError:
        if stash_ref:
            restore_stash(repo, stash_ref)
        raise SystemExit(1) from None
    else:
        if stash_ref:
            restore_stash(repo, stash_ref)
