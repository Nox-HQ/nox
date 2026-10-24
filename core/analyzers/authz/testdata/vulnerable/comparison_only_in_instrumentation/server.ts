import express from 'express'
import * as security from './lib/insecurity'
import { retrieveBasket } from './routes/basket'
const app = express()
app.use('/rest/basket', security.isAuthorized())
app.get('/rest/basket/:id', retrieveBasket())
