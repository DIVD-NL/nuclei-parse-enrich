# PowerShell Script to remove sensitive IPs from Git history
# Run with Administrator privileges to ensure proper file permissions

# Configure Git identity
git config --local user.email "github@vanderstap.info"
git config --local user.name "x-stp"

# Create a new orphan branch
git checkout --orphan temp_clean_branch

# Add all files from the current state (with cleaned IP)
git add -A

# Create a new commit with a clean message
git commit -m "Clean repository with documentation IP addresses"

# List all branches
Write-Host "Current branches:"
git branch -a

# Save the branch names
$branches = git branch -a | Where-Object { $_ -match '^\*?\s+(.*?)$' } | ForEach-Object { $matches[1] }

# Delete all local branches except the current one
foreach ($branch in $branches) {
    $trimmedBranch = $branch.Trim()
    # Skip remote branches and current branch
    if ($trimmedBranch -notlike "remotes/*" -and $trimmedBranch -ne "temp_clean_branch") {
        Write-Host "Deleting local branch: $trimmedBranch"
        git branch -D $trimmedBranch
    }
}

# Rename the temporary branch to main (or your desired branch name)
git branch -m feat/major-bump

# Force push to remote repository
git push -f origin feat/major-bump

Write-Host "Repository history has been cleaned and force-pushed."
Write-Host "Please ask all collaborators to run: git fetch --all && git reset --hard origin/feat/major-bump" 