"""Optional Neo4j loader for pushing CloudEnvironment graphs into Neo4j."""

from __future__ import annotations

from neo4j import GraphDatabase

from dbtrace.config import settings
from dbtrace.graph.builder import build_nx_graph
from dbtrace.schema import CloudEnvironment


def push_environment_to_neo4j(env: CloudEnvironment) -> int:
    """Upsert an environment's nodes and edges into Neo4j. Returns number of edges written."""
    g = build_nx_graph(env)
    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
    edge_count = 0
    try:
        with driver.session() as session:
            for nid, attrs in g.nodes(data=True):
                ntype = attrs.get("node_type", "Resource")
                session.run(
                    f"MERGE (n:{ntype} {{id: $id, env_id: $env_id}}) SET n.label = $label",
                    id=nid,
                    env_id=env.env_id,
                    label=attrs.get("label", nid),
                )
            for u, v, attrs in g.edges(data=True):
                rel = str(attrs.get("rel", "CONNECTED_TO")).replace(",", "_").replace("-", "_")
                session.run(
                    f"MATCH (a {{id: $u, env_id: $env_id}}), (b {{id: $v, env_id: $env_id}}) "
                    f"MERGE (a)-[:{rel}]->(b)",
                    u=u,
                    v=v,
                    env_id=env.env_id,
                )
                edge_count += 1
    finally:
        driver.close()
    return edge_count
