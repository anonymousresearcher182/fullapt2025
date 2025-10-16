#!/bin/bash
# Safe Anonymous Push Script

echo "=== ANONYMOUS COMMIT CHECKLIST ==="
echo ""

# Check 1: Verify identity
echo "✓ Checking git identity..."
NAME=$(git config user.name)
EMAIL=$(git config user.email)

if [ "$NAME" != "Anonymous Researcher 182" ] || [ "$EMAIL" != "anonymous.researcher.182@example.com" ]; then
    echo "❌ ERROR: Wrong identity detected!"
    echo "   Current: $NAME <$EMAIL>"
    echo "   Setting correct identity..."
    git config user.name "Anonymous Researcher 182"
    git config user.email "anonymous.researcher.182@example.com"
    echo "✅ Identity corrected!"
fi

echo "✅ Identity: $NAME <$EMAIL>"
echo ""

# Check 2: Show what will be committed
echo "✓ Files to be committed:"
git status --short
echo ""

# Check 3: Confirm
read -p "Continue with commit? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Aborted"
    exit 1
fi

# Check 4: Get commit message
echo "Enter commit message:"
read -r MESSAGE

# Check 5: Commit
git add .
git commit -m "$MESSAGE"

# Check 6: Verify author
echo ""
echo "✓ Verifying commit author..."
AUTHOR=$(git log -1 --format="%an <%ae>")
echo "   Author: $AUTHOR"

if [ "$AUTHOR" != "Anonymous Researcher 182 <anonymous.researcher.182@example.com>" ]; then
    echo "❌ ERROR: Wrong author in commit!"
    echo "   Fixing..."
    git commit --amend --reset-author --no-edit
    echo "✅ Fixed!"
fi

# Check 7: Push
echo ""
read -p "Push to GitHub? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git push origin main
    echo "✅ Pushed successfully!"
else
    echo "⚠️  Committed locally but not pushed"
fi

echo ""
echo "=== COMPLETE ==="
