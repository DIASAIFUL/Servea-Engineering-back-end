import express from 'express';
import auth from '../../middlewares/auth';
import userRole from '../user/user.constan';
import { blogController } from './blog.controller';
import { fileUploader } from '../../helper/fileUploder';
const router = express.Router();

router.post(
  '/',
  auth(userRole.Admin),
  fileUploader.upload.single('featuredImage'),
  blogController.createBlog,
);
router.get('/', blogController.getAllBlog);
router.get('/:id', blogController.getSingleBlog);
router.put(
  '/:id',
  auth(userRole.Admin),
  fileUploader.upload.single('featuredImage'),
  blogController.updateBlog,
);
router.delete('/:id', auth(userRole.Admin), blogController.deleteBlog);

export const blogRouter = router;
