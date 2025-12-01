/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable no-unused-vars */
import { NextFunction, Request, Response } from 'express';

const notFoundError = (req: Request, res: Response, next: NextFunction) => {
  res
    .status(404)
    .json({ success: false, message: 'Not Found', path: req.path });
};

export default notFoundError;
