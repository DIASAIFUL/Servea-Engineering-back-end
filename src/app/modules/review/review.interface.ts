import { Types } from "mongoose";

export interface IReview {
    project:Types.ObjectId;
    client:Types.ObjectId;
    engineer:Types.ObjectId;
    rating:number;
    review:string;
}