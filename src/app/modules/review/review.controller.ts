import { Request, Response } from 'express';
import catchAsync from '../../utils/catchAsycn';
import sendResponse from '../../utils/sendResponse';
import { reviewService } from './review.service';

const createReview = catchAsync(async (req: Request, res: Response) => {
  const clientId = req.user.id;
  const { projectId, engineerId, rating, review } = req.body;

  const newReview = await reviewService.addReview(
    clientId,
    projectId,
    engineerId,
    rating,
    review,
  );

  sendResponse(res, {
    statusCode: 201,
    success: true,
    message: 'Review submitted successfully',
    data: newReview,
  });
});

const getEngineerAllReviews = catchAsync(
  async (req: Request, res: Response) => {
    const { engineerId } = req.params;
    const reviews = await reviewService.getEngineerReviews(engineerId);

    sendResponse(res, {
      statusCode: 200,
      success: true,
      message: 'Engineer reviews fetched successfully',
      data: reviews,
    });
  },
);

const getsingleReview = catchAsync(async (req: Request, res: Response) => {
  const { reviewId } = req.params;
  const review = await reviewService.getsingleReview(reviewId);

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Review fetched successfully',
    data: review,
  });
});

const updateReview = catchAsync(async (req: Request, res: Response) => {
  const userId = req.user.id;
  const { reviewId } = req.params;
  const { rating, review } = req.body;

  const updated = await reviewService.updateReview(
    userId,
    reviewId,
    rating,
    review,
  );

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Review updated successfully',
    data: updated,
  });
});

const deleteReview = catchAsync(async (req: Request, res: Response) => {
  const userId = req.user.id;
  const { reviewId } = req.params;

  const result = await reviewService.deleteReview(userId, reviewId);

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: result.message,
  });
});

export const reviewController = {
  createReview,
  getEngineerAllReviews,
  updateReview,
  deleteReview,
  getsingleReview,
};
