// ============================================================
// controllers/graphController.js — IOC RELATIONSHIP GRAPH TRAVERSAL
// ============================================================
// Performs a Breadth-First Search (BFS) to traverse the database
// from a seed IOC and construct a relationship graph.
// Max nodes: 60, Depth limit: 2.
// ============================================================

const IOC = require('../models/IOC');
const ThreatActor = require('../models/ThreatActor');
const logger = require('../utils/logger');

// Helper to determine if two IOCs share tags, MITRE techniques, or source, and return relationship details
const getIOCDirectRelationships = (ioc1, ioc2, iocToActorsMap) => {
  const rels = [];

  // 1. Same tags (array overlap)
  const tags1 = ioc1.tags || [];
  const tags2 = ioc2.tags || [];
  const sharedTags = tags1.filter(t => tags2.includes(t));
  if (sharedTags.length > 0) {
    rels.push({
      type: 'shared-tag',
      label: `Tag: ${sharedTags[0]}`
    });
  }

  // 2. Same MITRE ATT&CK technique IDs
  const mitre1 = (ioc1.mitreTechniques || []).map(t => t.techniqueId).filter(Boolean);
  const mitre2 = (ioc2.mitreTechniques || []).map(t => t.techniqueId).filter(Boolean);
  const sharedMitre = mitre1.filter(id => mitre2.includes(id));
  if (sharedMitre.length > 0) {
    rels.push({
      type: 'mitre-technique',
      label: `Technique: ${sharedMitre[0]}`
    });
  }

  // 3. Same source feed
  if (ioc1.source && ioc2.source && ioc1.source === ioc2.source) {
    rels.push({
      type: 'shared-source',
      label: `Source: ${ioc1.source}`
    });
  }

  // 4. Same Threat Actor name (indirectly through threat actor nodes)
  const actors1 = (iocToActorsMap[ioc1._id.toString()] || []).map(a => a.name);
  const actors2 = (iocToActorsMap[ioc2._id.toString()] || []).map(a => a.name);
  const sharedActors = actors1.filter(a => actors2.includes(a));
  if (sharedActors.length > 0) {
    rels.push({
      type: 'threat-actor',
      label: `Actor: ${sharedActors[0]}`
    });
  }

  // 5. Same Campaign name (indirectly through campaign nodes)
  const campaigns1 = (iocToActorsMap[ioc1._id.toString()] || []).flatMap(a => (a.campaigns || []).map(c => c.name));
  const campaigns2 = (iocToActorsMap[ioc2._id.toString()] || []).flatMap(a => (a.campaigns || []).map(c => c.name));
  const sharedCampaigns = campaigns1.filter(c => campaigns2.includes(c));
  if (sharedCampaigns.length > 0) {
    rels.push({
      type: 'campaign',
      label: `Campaign: ${sharedCampaigns[0]}`
    });
  }

  return rels;
};

const getGraphData = async (req, res, next) => {
  try {
    const { iocId } = req.params;
    const userId = req.user.userId;

    // Step 1: Find the seed IOC
    const seedIOC = await IOC.findOne({ _id: iocId, submittedBy: userId, isActive: true }).lean();
    if (!seedIOC) {
      return res.status(404).json({ success: false, message: 'Seed IOC not found or access denied' });
    }

    // Step 2: Load all active IOCs of this user & active Threat Actors to build in-memory maps
    const [allUserIOCs, allActors] = await Promise.all([
      IOC.find({ submittedBy: userId, isActive: true }).lean(),
      ThreatActor.find({ isActive: true }).lean()
    ]);

    // Map: iocId (string) -> IOC object
    const iocMap = {};
    for (const ioc of allUserIOCs) {
      iocMap[ioc._id.toString()] = ioc;
    }

    // Map: iocId (string) -> Array of ThreatActor objects
    const iocToActorsMap = {};
    for (const actor of allActors) {
      for (const linkedId of actor.linkedIOCs || []) {
        const idStr = linkedId.toString();
        if (!iocToActorsMap[idStr]) {
          iocToActorsMap[idStr] = [];
        }
        iocToActorsMap[idStr].push(actor);
      }
    }

    // Map containing final selected nodes
    // key: Node ID, value: Node Object
    const finalNodes = new Map();

    // Set of visited IOC IDs during BFS traversal
    const visitedIocs = new Set([seedIOC._id.toString()]);

    // Helper to try adding a node if there's space (max 60 nodes total)
    const tryAddNode = (nodeId, nodeObj) => {
      if (finalNodes.has(nodeId)) return true;
      if (finalNodes.size >= 60) return false;
      finalNodes.set(nodeId, nodeObj);
      return true;
    };

    // Add seed IOC node first
    tryAddNode(seedIOC._id.toString(), {
      id: seedIOC._id.toString(),
      label: seedIOC.indicator,
      type: seedIOC.iocType,
      severity: seedIOC.severity,
      value: seedIOC.indicator,
      data: seedIOC
    });

    // Queue for BFS traversal: elements are { iocId, depth }
    const queue = [{ iocId: seedIOC._id.toString(), depth: 0 }];

    // Populate seed IOC's threat actors and campaigns as nodes
    const seedActors = iocToActorsMap[seedIOC._id.toString()] || [];
    for (const actor of seedActors) {
      const actorNodeId = `actor_${actor.name}`;
      const addedActor = tryAddNode(actorNodeId, {
        id: actorNodeId,
        label: actor.name,
        type: 'threat-actor',
        severity: 'Low',
        value: actor.name,
        data: actor
      });
      if (!addedActor) break;

      for (const campaign of actor.campaigns || []) {
        const campaignNodeId = `campaign_${campaign.name}`;
        const addedCampaign = tryAddNode(campaignNodeId, {
          id: campaignNodeId,
          label: campaign.name,
          type: 'campaign',
          severity: 'Low',
          value: campaign.name,
          data: campaign
        });
        if (!addedCampaign) break;
      }
    }

    // Step 3: Run BFS up to depth 2
    while (queue.length > 0 && finalNodes.size < 60) {
      const { iocId, depth } = queue.shift();
      const currentIoc = iocMap[iocId];
      if (!currentIoc) continue;

      if (depth < 2) {
        // Scan other IOCs for relationship overlap
        for (const otherIoc of allUserIOCs) {
          const otherIdStr = otherIoc._id.toString();
          if (visitedIocs.has(otherIdStr)) continue;

          const rels = getIOCDirectRelationships(currentIoc, otherIoc, iocToActorsMap);
          if (rels.length > 0) {
            // There is a relation, try to add this IOC node
            const addedIOC = tryAddNode(otherIdStr, {
              id: otherIdStr,
              label: otherIoc.indicator,
              type: otherIoc.iocType,
              severity: otherIoc.severity,
              value: otherIoc.indicator,
              data: otherIoc
            });

            if (addedIOC) {
              visitedIocs.add(otherIdStr);

              // Also add its associated threat actors and campaigns if space allows
              const otherActors = iocToActorsMap[otherIdStr] || [];
              for (const actor of otherActors) {
                const actorNodeId = `actor_${actor.name}`;
                const addedActor = tryAddNode(actorNodeId, {
                  id: actorNodeId,
                  label: actor.name,
                  type: 'threat-actor',
                  severity: 'Low',
                  value: actor.name,
                  data: actor
                });
                if (!addedActor) break;

                for (const campaign of actor.campaigns || []) {
                  const campaignNodeId = `campaign_${campaign.name}`;
                  const addedCampaign = tryAddNode(campaignNodeId, {
                    id: campaignNodeId,
                    label: campaign.name,
                    type: 'campaign',
                    severity: 'Low',
                    value: campaign.name,
                    data: campaign
                  });
                  if (!addedCampaign) break;
                }
              }

              // Enqueue the neighbor for the next BFS tier
              queue.push({ iocId: otherIdStr, depth: depth + 1 });
            }

            if (finalNodes.size >= 60) {
              break;
            }
          }
        }
      }
    }

    // Step 4: Construct edges based on final selected nodes
    const finalEdges = [];
    const edgeKeys = new Set();

    const addUniqueEdge = (source, target, relationship, label) => {
      const key = `${source}-${target}-${relationship}`;
      if (edgeKeys.has(key)) return;
      edgeKeys.add(key);
      finalEdges.push({ source, target, relationship, label });
    };

    const finalNodeIds = Array.from(finalNodes.keys());

    // 1. Edges between IOCs (shared-tag, mitre-technique, shared-source)
    for (let i = 0; i < finalNodeIds.length; i++) {
      for (let j = i + 1; j < finalNodeIds.length; j++) {
        const id1 = finalNodeIds[i];
        const id2 = finalNodeIds[j];

        const node1 = finalNodes.get(id1);
        const node2 = finalNodes.get(id2);

        // Direct relationships are only between IOC nodes
        if (node1.type === 'threat-actor' || node1.type === 'campaign') continue;
        if (node2.type === 'threat-actor' || node2.type === 'campaign') continue;

        const rels = getIOCDirectRelationships(node1.data, node2.data, iocToActorsMap);
        for (const rel of rels) {
          // If relationship is tag, mitre, or source, add direct edge
          if (rel.type === 'shared-tag' || rel.type === 'mitre-technique' || rel.type === 'shared-source') {
            addUniqueEdge(id1, id2, rel.type, rel.label);
          }
        }
      }
    }

    // 2. Edges between IOCs and Threat Actors / Campaigns
    for (const nodeId of finalNodeIds) {
      const node = finalNodes.get(nodeId);
      if (node.type === 'threat-actor' || node.type === 'campaign') continue;

      const actors = iocToActorsMap[nodeId] || [];
      for (const actor of actors) {
        const actorNodeId = `actor_${actor.name}`;
        if (finalNodes.has(actorNodeId)) {
          addUniqueEdge(nodeId, actorNodeId, 'threat-actor', `Actor: ${actor.name}`);

          for (const campaign of actor.campaigns || []) {
            const campaignNodeId = `campaign_${campaign.name}`;
            if (finalNodes.has(campaignNodeId)) {
              addUniqueEdge(nodeId, campaignNodeId, 'campaign', `Campaign: ${campaign.name}`);
            }
          }
        }
      }
    }

    // Convert Map values to array
    const nodesArray = Array.from(finalNodes.values()).map(n => ({
      id: n.id,
      label: n.label,
      type: n.type,
      severity: n.severity,
      value: n.value,
      data: n.data
    }));

    res.status(200).json({
      success: true,
      nodes: nodesArray,
      edges: finalEdges
    });

  } catch (err) {
    logger.error(`getGraphData error: ${err.message}`);
    next(err);
  }
};

module.exports = {
  getGraphData
};
