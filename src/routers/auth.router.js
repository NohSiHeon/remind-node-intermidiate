import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { HTTP_STATUS } from '../constants/http-status.constants.js';
import { MESSAGES } from '../constants/message.constant.js';
import { signUpValidator } from '../middlewares/validators.js/sign-up-validator.middleware.js';
import { prisma } from '../utils/prisma.util.js';
import { ACCESS_TOKEN_EXPIRES_IN, HASH_SALT_ROUNDS, REFRESH_TOKEN_EXPIRES_IN } from '../constants/auth.constant.js';
import { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } from '../constants/env.constant.js';
import { requireRefreshToken } from '../middlewares/require-refresh-token.middleware.js';
import { signInValidator } from '../middlewares/validators.js/sign-in-validator.middleware.js';

const authRouter = express.Router();

// 회원가입
authRouter.post('/sign-up', signUpValidator, async (req, res, next) => {
	try {
		const { email, password, passwordConfirm, name } = req.body;

		// 해당 이메일이 이미 있는지 조회
		const existedUser = await prisma.user.findUnique({
			where: {
				email
			}
		});

		// 이메일 중복 검증
		if (existedUser) {
			return res.status(HTTP_STATUS.CONFLICT).json({
				status: HTTP_STATUS.CONFLICT,
				message: MESSAGES.AUTH.COMMON.EMAIL.DUPLICATED
			});
		}

		// 비밀번호 암호화
		const hashedPassword = bcrypt.hashSync(password, HASH_SALT_ROUNDS);

		// 회원 생성
		const data = await prisma.user.create({
			data: {
				email,
				password: hashedPassword,
				name,
			},
		});

		data.password = undefined;

		return res.status(HTTP_STATUS.OK).json({
			status: HTTP_STATUS.OK,
			message: MESSAGES.AUTH.SIGN_UP.SUCCEED,
			data,
		})

	} catch (error) {
		next(error);
	}
});

// 로그인
authRouter.post('/sign-in', signInValidator, async (req, res, next) => {
	try {
		const { email, password } = req.body;

		const user = await prisma.user.findUnique({
			where: {
				email,
			},
		});

		const isPasswordMatched = user && bcrypt.compareSync(password, user.password);

		if (!isPasswordMatched) {
			return res.status(HTTP_STATUS.UNAUTHORIZED).json({
				status: HTTP_STATUS.UNAUTHORIZED,
				message: MESSAGES.AUTH.COMMON.UNAUTHORIZED,
			});
		}

		const payload = { id: user.id };
		const data = await generateAuthTokens(payload);

		return res.status(HTTP_STATUS.CREATED).json({
			status: HTTP_STATUS.CREATED,
			message: MESSAGES.AUTH.SIGN_IN.SUCCEED,
			data,
		});
	} catch (error) {
		next(error);
	}
});

// 리프레쉬 토큰 재발급
authRouter.post('/token', requireRefreshToken, async (req, res, next) => {
	try {
		const user = req.user;

		const payload = { id: user.id };

		const data = await generateAuthTokens(payload);

		return res.status(HTTP_STATUS.CREATED).json({
			status: HTTP_STATUS.CREATED,
			message: MESSAGES.AUTH.TOKEN.SUCCEED,
			data,
		});
	} catch (error) {
		next(error);
	}
});

// 로그아웃
authRouter.post('/sign-out', requireRefreshToken, async (req, res, next) => {
	try {
		const user = req.user;

		await prisma.refreshToken.update({
			where: {
				userId: user.id
			},
			data: {
				refreshToken: null,
			},
		});

		return res.status(HTTP_STATUS.CREATED).json({
			status: HTTP_STATUS.CREATED,
			message: MESSAGES.AUTH.SIGN_OUT.SUCCEED,
			data: { id: user.id },
		});
	} catch (error) {
		next(error);
	}
});

// 토큰 함수
const generateAuthTokens = async (payload) => {
	const userId = payload.id;
	const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });

	// 엑세스 토큰을 이용하여 리프레쉬 토큰 만들기
	const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });

	// 만들어진 리프레쉬 토큰 암호화
	const hashedRefreshToken = bcrypt.hashSync(refreshToken, HASH_SALT_ROUNDS);

	// 리프레쉬 토큰 저장
	await prisma.refreshToken.upsert({
		where: {
			userId,
		},
		update: {
			refreshToken: hashedRefreshToken,
		},
		create: {
			userId,
			refreshToken: hashedRefreshToken,
		},
	});

	return { accessToken, refreshToken };
};
export { authRouter };