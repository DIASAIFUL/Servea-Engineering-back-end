import mongoose from 'mongoose';
import { IReview } from './review.interface';

const reviewSchema = new mongoose.Schema<IReview>(
  {
    project: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Project',
      required: true,
    },
    client: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    engineer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    rating: { type: Number, required: true, min: 1, max: 5 },
    review: { type: String },
  },
  { timestamps: true },
);

const Review = mongoose.model<IReview>('Review', reviewSchema);
export default Review;
