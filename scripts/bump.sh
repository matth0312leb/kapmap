#!/bin/sh
# Met à jour le numéro de version (index.html + version.json) avant chaque publication
V=$(date +%s)
echo "{\"v\":\"$V\"}" > version.json
sed -i "s/var BUILD = '[0-9]*';/var BUILD = '$V';/" index.html
