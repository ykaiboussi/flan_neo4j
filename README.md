# Flan Neo4j

Lightweight schema on read visulization tool to create relationships off [Flan](https://github.com/cloudflare/flan) reports and policies

![dry_run](https://github.com/ykaiboussi/flan_neo4j/blob/main/images/dry_run.png)

## Installation

Install neo4j docker image + APOC plugin

```
docker run \
    -p 7474:7474 -p 7687:7687 \
    -v $PWD/data:/data -v $PWD/plugins:/plugins \
    --name neo4j-apoc \
    -e NEO4J_apoc_export_file_enabled=true \
    -e NEO4J_apoc_import_file_enabled=true \
    -e NEO4J_apoc_import_file_use__neo4j__config=true \
    -e NEO4JLABS_PLUGINS=\[\"apoc\"\] \
    neo4j:4.0
```

 ## Usage

```
 ./flan_neo4j -policy example/policy.json -report example/flan_report.json
```