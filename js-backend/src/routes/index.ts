import express , { Request, Response } from 'express';

const indexRouter = express.Router();

indexRouter.get('/', (_req: Request, res: Response) =>
    res.status(200).json({ message: 'Welcome to Express API template' })
  
);

export default indexRouter;