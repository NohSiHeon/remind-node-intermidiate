import express from 'express';
import { authRouter } from './auth.router.js';
import { usersRouter } from './users.router.js';
import { resumesRouter } from './resumes.router.js';
import { requireAccessToken } from '../middlewares/require-access-token.middleware.js';


const apiRouter = express.Router();

apiRouter.use('/auth', authRouter);

// users
apiRouter.use('/users', usersRouter);

// resumes
apiRouter.use('/resumes', requireAccessToken, resumesRouter);

export { apiRouter };