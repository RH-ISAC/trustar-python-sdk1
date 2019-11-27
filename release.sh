# usage: ./release.sh 0.3.x

VERSION=$1

# validate version parameter passed
[[ -z "$VERSION" ]] && { echo "VERSION is required" ; exit 1; }

# replace version in file
echo "Replacing version in trustar/version.py"
cat > trustar/version.py <<- EOM
__version__ = "$VERSION"
__api_version__ = "1.3"
EOM
git add trustar/version.py
git commit -m "Bump version file"
git push

# tag repository
echo "Tagging $VERSION"
git tag $VERSION -m "Bump version"
git push --tags origin master

# package and upload
echo "Releasing version $VERSION"
python setup.py sdist
twine upload --skip-existing dist/trustar-${VERSION}.tar.gz
