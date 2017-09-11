#! /bin/bash
## vim:set ts=4 sw=4 et:

#
# Automatic build of LIEF
# Repo: https://github.com/lief-project/packages
# Mostly inspired by https://github.com/upx/upx-automatic-builds

set -e; set -o pipefail

if [[ $TRAVIS_OS_NAME == osx ]]; then
argv0=$0; argv0abs=$(greadlink -en -- "$0"); argv0dir=$(dirname "$argv0abs")
else
argv0=$0; argv0abs=$(readlink -en -- "$0"); argv0dir=$(dirname "$argv0abs")
fi
set -x # debug

if [[ $TRAVIS_OS_NAME == osx ]]; then
# use GNU coreutils ("brew install coreutils")
date() {
    gdate "$@"
}
readlink() {
    greadlink "$@"
}
sha256sum() {
    gsha256sum "$@"
}
fi

if [[ -n $APPVEYOR_JOB_ID ]]; then
openssl() {
    /usr/bin/openssl "$@"
}
sort() {
    /usr/bin/sort "$@"
}
fi

fix_home_ssh_perms() {
    if [[ -d ~/.ssh ]]; then
        if [[ -x /usr/sbin/restorecon ]]; then
            /usr/sbin/restorecon -v -R ~/.ssh || true
        fi
        chmod -c -R go-rwx ~/.ssh || true
    fi
}

# =================
# SETUP BRANCH NAME
# =================
branch=
if [[ -n $APPVEYOR_JOB_ID ]]; then
    branch=$APPVEYOR_REPO_BRANCH
    if [[ -n $APPVEYOR_PULL_REQUEST_NUMBER ]]; then exit 0; fi
else
    branch=$TRAVIS_BRANCH
    if [[ "$TRAVIS_PULL_REQUEST" != "false" ]]; then exit 0; fi
fi

case $branch in
    devel*) ;;
    master*) ;;
    deploy*) ;;
    *) exit 0;;
esac

# get $rev, $branch and $git_user
LIEF_SRCDIR=
[[ -z $LIEF_SRCDIR ]] && LIEF_SRCDIR=$(readlink -mn -- $argv0dir/..)
cd / && cd $LIEF_SRCDIR || exit 1
rev=$(git rev-parse --verify HEAD)
timestamp=$(git log -n1 --format='%at' $rev)
date=$(TZ=UTC0 date -d "@$timestamp" '+%Y%m%d-%H%M%S')
#branch="$branch-$date-${rev:0:6}"
branch="lief-$branch-latest"
if [[ -n $APPVEYOR_JOB_ID ]]; then
    branch="$branch"
    git_user="AppVeyor CI"
else
    branch="$branch"
    git_user="Travis CI"
fi
unset timestamp date

# ========================
# SETUP 'deploy' DIRECTORY
# ========================
if [[ -n $APPVEYOR_JOB_ID ]]; then
    [[ -z $LIEF_BUILDDIR ]] && LIEF_BUILDDIR=$(readlink -mn -- .)
else
    [[ -z $LIEF_BUILDDIR ]] && LIEF_BUILDDIR=$(readlink -mn -- ./build)
fi
echo $LIEF_BUILDDIR
cd / && cd $LIEF_BUILDDIR || exit 1

mkdir deploy || exit 1
chmod 700 deploy
cd deploy || exit 1

# ==================
# CLONE - ADD - PUSH
# ==================
new_branch=0
if ! git clone -b "$branch" --single-branch https://github.com/lief-project/packages.git; then
    git  clone -b master    --single-branch https://github.com/lief-project/packages.git
    new_branch=1
fi
cd packages || exit 1
chmod 700 .git

git config user.name "$git_user"
git config user.email "lief@quarkslab.com"

if [[ $new_branch == 1 ]]; then
    git checkout --orphan "$branch"
    git reset --hard || true
fi

git reset --soft `git rev-list --all | tail -1`
git ls-files -v


/bin/cp -rf $LIEF_BUILDDIR/api/python/dist/*.zip .
/bin/cp -rf $LIEF_BUILDDIR/api/python/dist/*.egg .

if [[ -n $APPVEYOR_JOB_ID ]]; then
    /bin/cp -rf $LIEF_BUILDDIR/*.zip .
else
    /bin/cp -rf $LIEF_BUILDDIR/*.tar.gz .
fi

git add .

if git diff --cached --exit-code --quiet >/dev/null; then
    # nothing to do ???
    exit 0
fi

now=$(date '+%s')

git commit --date="$now" -m "Automatic build - ${rev:0:7} - Python ${PYTHON_VERSION}"
git ls-files -v
git log --pretty=fuller

umask 077
[[ -d ~/.ssh ]] || mkdir ~/.ssh
fix_home_ssh_perms
repo=$(git config remote.origin.url)
ssh_repo=${repo/https:\/\/github.com\//git@github.com:}
eval $(ssh-agent -s)
set +x # IMPORTANT
openssl aes-256-cbc -K $LIEF_AUTOMATIC_BUILDS_KEY -iv $LIEF_AUTOMATIC_BUILDS_IV -in "$LIEF_SRCDIR/.github/deploy-key.enc" -out .git/deploy-key -d
set -x
chmod 600 .git/deploy-key
ssh-add .git/deploy-key
fix_home_ssh_perms
ssh-keyscan -H github.com >> ~/.ssh/known_hosts
fix_home_ssh_perms
#
let i=0 || true
while true; do
    if [[ $i -ge 10 ]]; then
        echo "ERROR: git push failed"
        exit 1
    fi
    if [[ $new_branch == 1 ]]; then
        if git push --force -u $ssh_repo "$branch"; then break; fi
    else
        if git push --force $ssh_repo "$branch"; then break; fi
    fi
    git branch -a -v
    git fetch -v origin "$branch"
    git branch -a -v
    git rebase -s recursive -X theirs FETCH_HEAD
    git branch -a -v
    sleep $((RANDOM % 5 + 1))
    let i+=1
done

exit 0
