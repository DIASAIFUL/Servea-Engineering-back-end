import { Types } from "mongoose";

export interface IBlog{
  title: string;
  content: string;
  authorId?: Types.ObjectId;
  featuredImage?: string;
  tags?: string[];
  published: boolean;
}


