import jwt from 'jsonwebtoken';
import { HTTP_STATUS } from "../constants/http-status.constants.js";
import { MESSAGES } from "../constants/message.constant.js";
import { REFRESH_TOKEN_SECRET } from '../constants/env.constant.js';
import { prisma } from '../utils/prisma.util.js';
import bcrypt from 'bcrypt';

export const requireRefreshToken = async (req, res, next) => {
	try {
		// 인증 정보 파싱
		const authorization = req.headers.authorization;

		// Authorization이 없는 경우
		if (!authorization) {
			return res.status(HTTP_STATUS.UNAUTHORIZED).json({
				status: HTTP_STATUS.UNAUTHORIZED,
				message: MESSAGES.AUTH.COMMON.JWT.NO_TOKEN,
			});
		}

		// authorization을 type과 RefreshToken 으로 나눠서 분해 할당
		const [type, refreshToken] = authorization.split(' ');

		// JWT 표준 인증 형태와 일치하지 않는 경우
		if (type !== 'Bearer') {
			return res.status(HTTP_STATUS.UNAUTHORIZED).json({
				status: HTTP_STATUS.UNAUTHORIZED,
				message: MESSAGES.AUTH.COMMON.JWT.NOT_SUPPORTED_TYPE,
			});
		}

		//RefreshToken이 없는 경우
		if (!refreshToken) {
			return res.status(HTTP_STATUS.UNAUTHORIZED).json({
				status: HTTP_STATUS.UNAUTHORIZED,
				message: MESSAGES.AUTH.COMMON.JWT.NO_TOKEN,
			});
		}

		let payload;
		try {
			payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
		} catch (error) {
			// RefreshToken의 유효기간이 지난 경우
			if (error.name === 'TokenExpiredError') {
				return res.status(HTTP_STATUS.UNAUTHORIZED).json({
					status: HTTP_STATUS.UNAUTHORIZED,
					message: MESSAGES.AUTH.COMMON.JWT.EXPIRED,
				});
			}
			// 그 밖의 RefreshToken 검증에 실패한 경우
			else {
				return res.status(HTTP_STATUS.UNAUTHORIZED).json({
					status: HTTP_STATUS.UNAUTHORIZED,
					message: MESSAGES.AUTH.COMMON.JWT.INVALID,
				});
			}
		}
		const { id } = payload;

		// DB에서 RefreshToken을 조회
		// 넘겨받은 RefreshToken과 비교
		const existedRefreshToken = await prisma.refreshToken.findUnique({
			where: {
				userId: id,
			},
		});
		const isValidRefreshToken = existedRefreshToken?.refreshToken && bcrypt.compareSync(refreshToken, existedRefreshToken.refreshToken);

		if (!isValidRefreshToken) {
			return res.status(HTTP_STATUS.UNAUTHORIZED).json({
				status: HTTP_STATUS.UNAUTHORIZED,
				message: MESSAGES.AUTH.COMMON.JWT.DISCARDED_TOKEN,
			});
		}
		// Payload에 담긴 사용자 ID와 일치하는 사용자가 없는 경우

		const user = await prisma.user.findUnique({
			where: {
				id
			},
			omit: {
				password: true
			},
		});

		if (!user) {
			return res.status(HTTP_STATUS.UNAUTHORIZED).json({
				status: HTTP_STATUS.UNAUTHORIZED,
				message: MESSAGES.AUTH.COMMON.JWT.NO_USER,
			});
		}


		req.user = user;
		next();
	} catch (error) {
		next(error);
	}
}
