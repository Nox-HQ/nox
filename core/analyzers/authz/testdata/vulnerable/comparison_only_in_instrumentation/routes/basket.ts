import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'
import * as challengeUtils from '../lib/challengeUtils'
import * as security from '../lib/insecurity'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id
    const basket = await BasketModel.findOne({ where: { id } }) // expect: AUTHZ-001
    challengeUtils.solveIf('basketAccess', () => {
      const user = security.authenticatedUsers.from(req)
      return user && user.bid != parseInt(id, 10)
    })
    res.json(basket)
  }
}
