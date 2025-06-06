const { CosmosClient } = require("@azure/cosmos");
require('dotenv').config();

const client = new CosmosClient({
  endpoint: process.env.COSMOS_DB_ENDPOINT,
  key: process.env.COSMOS_DB_KEY,
});

const database = client.database(process.env.COSMOS_DB_DATABASE);
const container = database.container(process.env.COSMOS_DB_CONTAINER);

module.exports = container;
