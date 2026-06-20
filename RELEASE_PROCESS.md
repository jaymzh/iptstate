# Release process

## Bump version

```shell
vi iptstate.cc iptstate.spec
```

## Add appropriate Changelog entries

```shell
vi Changelog
```

## Commit & Push

## Tag a release

```shell
version="2.2.7" # update accordingly
git tag -a "v$version" -m "iptstate version $version"
git push origin --tags
```

## Create GH release

## Inform packagers
