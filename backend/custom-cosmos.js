// custom-cosmos.js
const { CosmosClient } = require('@azure/cosmos');

const createCustomContainer = ({ endpoint, key, databaseId, containerId }) => {
  try {
    const client = new CosmosClient({ endpoint, key });
    const database = client.database(databaseId);
    const container = database.container(containerId);
    return container;
  } catch (error) {
    throw new Error("Invalid Cosmos DB configuration.");
  }
};

module.exports = { createCustomContainer };
