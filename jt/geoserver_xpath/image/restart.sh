#!/usr/bin/env bash
set -euo pipefail

source_dir=/srv/challenge/geotools
repo=/opt/maven/repository
web_lib=/opt/apache-tomcat-9.0.86/webapps/geoserver/WEB-INF/lib
stage=$(mktemp -d /tmp/geoserver-jars.XXXXXX)
trap 'rm -rf "$stage"' EXIT

cd "$source_dir"
mvn -o -B -DskipTests -Dmaven.repo.local="$repo" \
    -pl :gt-main,:gt-xsd-core,:gt-app-schema -am package

install -m 0644 \
    modules/extension/app-schema/app-schema/target/gt-app-schema-31.1.jar \
    "$stage/gt-app-schema-31.1.jar"
install -m 0644 \
    modules/extension/complex/target/gt-complex-31.1.jar \
    "$stage/gt-complex-31.1.jar"
install -m 0644 \
    modules/extension/xsd/xsd-core/target/gt-xsd-core-31.1.jar \
    "$stage/gt-xsd-core-31.1.jar"

rm -f /run/geoserver/arena.ready
/arena/service-control.sh stop
for jar in gt-app-schema-31.1.jar gt-complex-31.1.jar gt-xsd-core-31.1.jar; do
    install -m 0644 "$stage/$jar" "$web_lib/$jar.new"
done
for jar in gt-app-schema-31.1.jar gt-complex-31.1.jar gt-xsd-core-31.1.jar; do
    mv -f "$web_lib/$jar.new" "$web_lib/$jar"
done
/arena/service-control.sh start
/arena/service-control.sh ready
/arena/facility.py verify-bootstrap
touch /run/geoserver/arena.ready
echo 'GeoTools reactor rebuilt and GeoServer reloaded'
