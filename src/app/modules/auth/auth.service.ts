/* eslint-disable no-unused-vars */
/* eslint-disable @typescript-eslint/no-unused-vars */
import { JwtPayload, Secret } from 'jsonwebtoken';
import config from '../../config';
import AppError from '../../error/appError';
import { IUser } from '../user/user.interface';
import User from '../user/user.model';
import { jwtHelpers } from '../../helper/jwtHelpers';
import sendMailer from '../../helper/sendMailer';

import bcrypt from 'bcryptjs';
import createOtpTemplate from '../../utils/createOtpTemplate';

import userRole from '../user/user.constan';
import Service from '../service/service.model';
import Industry from '../industri/industri.model';
import { fileUploader } from '../../helper/fileUploder';

const registerUser = async (
  payload: Partial<IUser>,
  file?: Express.Multer.File,
) => {
  // check existing user
  const exist = await User.findOne({ email: payload.email });
  if (exist) throw new AppError(400, 'User already exists');

  // profile image upload
  if (file) {
    const addProfileImage = await fileUploader.uploadToCloudinary(file);
    payload.profileImage = addProfileImage.secure_url;
  } else {
    const idx = Math.floor(Math.random() * 100);
    payload.profileImage = `https://avatar.iran.liara.run/public/${idx}.png`;
  }

  // engineer field validation
  if (payload.role === userRole.Engineer) {
    const requiredFields = [
      'professionTitle',
      'location',
      'skills',
      'industry',
      'service',
      'bio',
    ];

    for (const field of requiredFields) {
      if (!payload[field as keyof IUser]) {
        throw new AppError(
          400,
          `Missing required field for engineer: ${field}`,
        );
      }
    }
  }

  // --------------------------
  // 🔥 Add OTP + status system
  // --------------------------

  // OTP generate
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  payload.otp = otp;
  payload.otpExpiry = new Date(Date.now() + 20 * 60 * 1000); // 20 minutes

  // email verification default status
  payload.verified = false;
  payload.status = 'pending';

  // create user
  const result = await User.create(payload);

  // industry push
  if (payload.industry) {
    const industry = await Industry.findById(payload.industry);
    if (!industry) {
      await User.findByIdAndDelete(result._id);
      throw new AppError(400, 'Industry not found');
    }
    industry.users.push(result._id);
    await industry.save();
  }

  // service push
  if (payload.service) {
    const service = await Service.findById(payload.service);
    if (!service) {
      await User.findByIdAndDelete(result._id);
      throw new AppError(400, 'Service not found');
    }
    service.users.push(result._id);
    await service.save();
  }

  // ---------------------------------
  // 🔥 Send OTP email to the user
  // ---------------------------------
  await sendMailer(
    result.email,
    result.firstName + ' ' + result.lastName,
    createOtpTemplate(otp, result.email, result.firstName + ' ' + result.lastName,'Servea Engineering Platform'),
  );

  return {
    message: 'Registration successful. Please verify your email.',
    userId: result._id,
  };
};

const loginUser = async (payload: Partial<IUser>) => {
  const user = await User.findOne({ email: payload.email});
  if (!user) throw new AppError(401, 'User not found');
  if (!payload.password) throw new AppError(400, 'Password is required');
  
  const isPasswordMatched = await bcrypt.compare(
    payload.password,
    user.password,
  );
  if (!isPasswordMatched) throw new AppError(401, 'Password not matched');
  if (user.status !== 'active') throw new AppError(401, 'Verify your email to activate your account');
  const accessToken = jwtHelpers.genaretToken(
    { id: user._id, role: user.role, email: user.email },
    config.jwt.accessTokenSecret as Secret,
    config.jwt.accessTokenExpires,
  );

  const refreshToken = jwtHelpers.genaretToken(
    { id: user._id, role: user.role, email: user.email },
    config.jwt.refreshTokenSecret as Secret,
    config.jwt.refreshTokenExpires,
  );

  user.lastLogin = new Date();
  await user.save();

  const { password, ...userWithoutPassword } = user.toObject();
  return { accessToken, refreshToken, user: userWithoutPassword };
};

const verifyEmailStatus = async (email: string, otp: string) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(404, 'User not found');

  // first check OTP is correct or not
  if (!user.otp || user.otp !== otp) {
    throw new AppError(400, 'Invalid OTP');
  }

  // check OTP expiry
  if (!user.otpExpiry || user.otpExpiry < new Date()) {
    throw new AppError(400, 'OTP expired');
  }

  // update status and verified
  user.status = 'active';
  user.verified = true;
  user.otp = undefined;
  user.otpExpiry = undefined;

  await user.save();

  const { password, ...userWithoutPassword } = user.toObject();
  return userWithoutPassword;
};


const refreshToken = async (token: string) => {
  const varifiedToken = jwtHelpers.verifyToken(
    token,
    config.jwt.refreshTokenSecret as Secret,
  ) as JwtPayload;

  const user = await User.findById(varifiedToken.id);
  if (!user) throw new AppError(401, 'User not found');

  const accessToken = jwtHelpers.genaretToken(
    { id: user._id, role: user.role, email: user.email },
    config.jwt.accessTokenSecret as Secret,
    config.jwt.accessTokenExpires,
  );

  const { password, ...userWithoutPassword } = user.toObject();
  return { accessToken, user: userWithoutPassword };
};

const forgotPassword = async (email: string) => {
  const user = await User.findOne({ email });
  
  if (!user) throw new AppError(401, 'User not found');
  

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  user.otp = otp;
  user.otpExpiry = new Date(Date.now() + 20 * 60 * 1000); // 20 mins
  await user.save();

  await sendMailer(
    user.email,
    user.firstName + ' ' + user.lastName,
    createOtpTemplate(otp, user.email, 'Circuitdaddy'),
  );

  return { message: 'OTP sent to your email' };
};

const verifyEmailOTP = async (email: string, otp: string) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(401, 'User not found');
  console.log(user.otp, otp, user.otpExpiry);
  if (user.otp !== otp || !user.otpExpiry || user.otpExpiry < new Date()) {
    throw new AppError(400, 'Invalid or expired OTP');
  }

  user.verified = true;
  user.status = 'active';
  user.otp = undefined;
  user.otpExpiry = undefined;
  await user.save();

  return { message: 'Email verified successfully' };
};

const resetPassword = async (email: string, newPassword: string) => {
  const user = await User.findOne({ email });
  if (!user) throw new AppError(404, 'User not found');
  if (!user.verified) throw new AppError(400, 'Email not verified');
  if (!newPassword) throw new AppError(400, 'Password is required');

  user.password = newPassword;
  user.otp = undefined;
  user.otpExpiry = undefined;
  user.verified = false;
  await user.save();

  // Auto-login after reset
  const accessToken = jwtHelpers.genaretToken(
    { id: user._id, role: user.role, email: user.email },
    config.jwt.accessTokenSecret as Secret,
    config.jwt.accessTokenExpires,
  );
  const refreshToken = jwtHelpers.genaretToken(
    { id: user._id, role: user.role, email: user.email },
    config.jwt.refreshTokenSecret as Secret,
    config.jwt.refreshTokenExpires,
  );

  const { password, ...userWithoutPassword } = user.toObject();
  return {
    accessToken,
    refreshToken,
    user: userWithoutPassword,
  };
};

const changePassword = async (
  userId: string,
  oldPassword: string,
  newPassword: string,
) => {
  const exist = await User.findById(userId);
  if (!exist) throw new AppError(401, 'User not found');

  const isPasswordMatched = await bcrypt.compare(oldPassword, exist.password);
  if (!isPasswordMatched) throw new AppError(401, 'Password not matched');

  exist.password = newPassword;
  await exist.save();

  return { message: 'Password changed successfully' };
};

export const authService = {
  registerUser,
  loginUser,
  verifyEmailStatus,
  refreshToken,
  forgotPassword,
  verifyEmailOTP,
  resetPassword,
  changePassword,
};
