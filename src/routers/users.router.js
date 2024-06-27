import express from 'express';
import { requireAccessToken } from '../middlewares/require-access-token.middleware.js';
import { HTTP_STATUS } from '../constants/http-status.constants.js';
import { MESSAGES } from '../constants/message.constant.js';

const usersRouter = express.Router();

// 내 정보 조회
usersRouter.get('/me', requireAccessToken, async (req, res, next) => {
	try {
		const data = req.user;

		return res.status(HTTP_STATUS.OK).json({
			status: HTTP_STATUS.OK,
			message: MESSAGES.USERS.READ_ME.SUCCEED,
			data
		});

	} catch (error) {
		next(error);
	}
});

export { usersRouter };