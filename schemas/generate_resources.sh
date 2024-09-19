#!/bin/sh

set -o errexit

script_dir=$(dirname "$0")
top_level_schemas_file=$(realpath "$1")
sdk_go_file=$(realpath "$2")
work_dir=$(pwd)

cd ${script_dir}

python3 schemas_downloader.py ${top_level_schemas_file}

cat ${top_level_schemas_file} | 
{
    while IFS= read schema
    do
        all_schemas="${all_schemas} ${schema}.json"
    done

    go-jsonschema ${all_schemas} --package resources --resolve-extension .json --output ${sdk_go_file}
    echo Done generating $sdk_go_file
}

cd $work_dir
