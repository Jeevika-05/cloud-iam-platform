import { Router } from 'express';
import { authenticate } from '../../shared/middleware/authenticate.js';
import { requirePermission } from '../../shared/middleware/requirePermission.js';
import { successResponse, errorResponse } from '../../shared/utils/response.js';
import { getNeo4jDriver } from '../../shared/db/neo4j.js';
import neo4j from 'neo4j-driver';

const router = Router();

router.get(
  ['/', '/attack-paths'],
  authenticate,
  requirePermission('security:view'),
  async (req, res) => {
    let session;
    try {
      const { type = 'attack-defense' } = req.query;
      const limit = Math.min(parseInt(req.query.limit) || 50, 100);
      const severity = req.query.severity || null;

      const queries = {
        'attack-defense': `
          MATCH (a:Event {event_type:'ATTACK'})
          WHERE ($severity IS NULL OR a.severity = $severity)
          OPTIONAL MATCH (a)<-[r1:TRIGGERED_DEFENSE]-(d:Event {event_type:'DEFENSE'})
          OPTIONAL MATCH (d)-[r2:APPLIED]->(da:DefenseAction)
          RETURN a, d, r1, da, r2
          ORDER BY a.timestamp DESC
          LIMIT $limit
        `,
        'attack-chain': `
          MATCH (e:Event)-[r:NEXT]->(x)
          WHERE ($severity IS NULL OR e.severity = $severity)
          RETURN e, r, x
          LIMIT $limit
        `,
        'user-attack': `
          MATCH (n)-[r:ACTED|TARGETED]->(e:Event)
          WHERE ($severity IS NULL OR e.severity = $severity)
          RETURN n, r, e
          LIMIT $limit
        `,
        'recent': `
          MATCH (e:Event)
          WHERE e.timestamp IS NOT NULL AND ($severity IS NULL OR e.severity = $severity)
          OPTIONAL MATCH (e)-[r]->(x)
          RETURN e, r, x
          ORDER BY e.timestamp DESC
          LIMIT $limit
        `
      };

      if (!queries[type]) {
        return errorResponse(res, 'Invalid graph query type', 400, 'INVALID_GRAPH_TYPE');
      }

      const driver = getNeo4jDriver();
      session = driver.session({ defaultAccessMode: neo4j.session.READ });

      const result = await session.run(queries[type], { limit: neo4j.int(limit), severity });

      const nodesMap = new Map();
      const edgesMap = new Map();

      const processNode = (node) => {
        if (!node || !node.labels) return;

        const id = (node.elementId || node.identity).toString();

        if (!nodesMap.has(id)) {
          nodesMap.set(id, {
            id,
            label: node.labels[0] || 'Unknown',
            group: node.labels[0] || 'Unknown',
            ...node.properties,
          });
        }
      };

      const processEdge = (edge) => {
        if (!edge || !edge.startNodeElementId || !edge.endNodeElementId) return;

        const source = edge.startNodeElementId.toString();
        const target = edge.endNodeElementId.toString();
        const type = edge.type;

        const id = `${source}-${target}-${type}`;

        if (!edgesMap.has(id)) {
          edgesMap.set(id, {
            id,
            source,
            target,
            type,
            ...edge.properties,
          });
        }
      };

      result.records.forEach((record) => {
        record.keys.forEach((key) => {
          const item = record.get(key);
          if (!item) return;

          // Check if item is a Node or Relationship based on native properties
          if (item.labels) {
            processNode(item);
          } else if (item.type && (item.startNodeElementId || item.start)) {
            processEdge(item);
          }
        });
      });

      return successResponse(
        res,
        {
          type,
          nodes: Array.from(nodesMap.values()).slice(0, 200),
          edges: Array.from(edgesMap.values()).slice(0, 200),
        },
        'Attack paths retrieved successfully',
        200,
        'GRAPH_ATTACK_PATHS'
      );
    } catch (error) {
      return errorResponse(res, 'Failed to fetch graph data', 500, 'GRAPH_ERROR', error.message);
    } finally {
      if (session) {
        await session.close();
      }
    }
  }
);

export default router;
