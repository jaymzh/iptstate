# Release process

0. Bump version

```shell
vi iptstate.cc iptstate.spec
```

1. Add appropriate Changelog entries

```shell
vi Changelog
```

2. Commit & Push

3. Tag a release

```shell
version="2.2.7" # update accordingly
git tag -a "v$version" -m "iptstate version $version"
git push origin --tags
```

4. Make a tarball

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

5. Sign

```shell
gpg -ab /tmp/iptstate-$version.tar.bz2
```

6. Upload

7. Update website
