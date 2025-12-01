import express from 'express';
import userRole from '../user/user.constan';
import { reviewController } from './review.controller';
import auth from '../../middlewares/auth';

const router = express.Router();

router.post('/', auth(userRole.User), reviewController.createReview);
router.get('/:engineerId', reviewController.getEngineerAllReviews);
router.put('/:reviewId', auth(userRole.User), reviewController.updateReview);
router.delete('/:reviewId', auth(userRole.User), reviewController.deleteReview);
router.get('/single/:reviewId', reviewController.getsingleReview);

export const reviewRouter = router;
