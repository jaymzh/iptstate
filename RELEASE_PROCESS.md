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

## Make a tarball

```shell
git archive --format=tar --prefix=iptstate-$version/ v$version \
  > /tmp/iptstate-$version-prep.tar
cd /tmp && tar xf iptstate-$version-prep.tar
cd /tmp/iptstate-$version
# poke around
cd ..
mv iptstate-$version-prep.tar iptstate-$version.tar
bzip2 iptstate-$version.tar
```

## Sign

```shell
gpg -ab /tmp/iptstate-$version.tar.bz2
```

## Upload

## Update website
