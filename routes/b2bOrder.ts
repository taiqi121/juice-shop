/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm = require('vm')
import { type Request, type Response, type NextFunction } from 'express'
import challengeUtils = require('../lib/challengeUtils')

import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const safeEval = require('notevil')
const challenges = require('../data/datacache').challenges

module.exports = function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (!utils.disableOnContainerEnv()) {
      const orderLinesData = body.orderLinesData || ''
      try {
        // Safe validation of orderLinesData - must be valid JSON array
        if (typeof orderLinesData !== 'string') {
          throw new Error('orderLinesData must be a string')
        }
        
        // Validate JSON structure without code execution
        let parsedData
        try {
          parsedData = JSON.parse(orderLinesData)
        } catch {
          throw new Error('orderLinesData must be valid JSON')
        }
        
        // Validate array of order lines
        if (!Array.isArray(parsedData)) {
          throw new Error('orderLinesData must be an array')
        }
        
        // Validate each order line
        for (const line of parsedData) {
          if (typeof line !== 'object' || line === null) {
            throw new Error('Each order line must be an object')
          }
          if (typeof line.quantity !== 'number' || line.quantity < 1) {
            throw new Error('Invalid quantity in order line')
          }
          if (typeof line.productId !== 'number') {
            throw new Error('Invalid productId in order line')
          }
        }
        
        // No code execution - just validate and return success
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        next(err)
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(new Date() + '_B2B')
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
