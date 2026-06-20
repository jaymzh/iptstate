# Release process

## Bump version

```shell
vi iptstate.cc iptstate.spec
```

## Add appropriate Changelog entries

```shell
vi CHANGELOG.md
```

## Make PR & Merge

## Tag a release

```shell
version="2.2.7" # update accordingly
git tag -a "v$version" -m "iptstate version $version" -s
git push origin --tags
```

## Create GH release

## Inform packagers
