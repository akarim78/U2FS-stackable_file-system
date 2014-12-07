U2FS Stackable Files System
----------------------------
U2FS supports following functionality:

1. When you look up a file in u2fs, which exists in both the branches, left
   branch takes priority and content of left branch is exposed. In case, it
   exists in only on directory, then it is shown from its respective
   directory. For directories if they exist in both the branches, their
   content is merged recursively and displayed. Duplicates are eliminated.


2. When you create a new file, it by defualt get create in LB. If you try to
   create a file in directory which exists in RB, then its complete directory
   structure is copied to LB and then the file is created in LB. This concept
   of copying the entire directory dtructure is called copyup.

3. When you modify an existing file in LB, it gets modified there.  But if a
   user tries to modify a file that exists in RB only, then again the entire 
   directory structure is copied to LB with the file being modified and then 
   the file is modified in LB. Original file in RB remains untouched.

4. When you delete a file (or directory) from LB it gets deleted normally.
   But when you have to delete a file which exists only in RB then a mask
   file is created in LB which tells U2FS that the original file is deleted
   from RB. In case the directory structure doesn't exist in LB, the directory
   structure is copied and then the mask file is created. In case a file
   exists in both LB and RB then the file in LB is deleted and and mask file
   for RB is created in LB. The mask file is called a whiteout and the name
   of whiteout file starts with .wh.filename.

5. If same files and/or directories exists in both LB and RB then duplicates
   will not be displayed. File from LB will be displayed. Duplicate elimination    is handled at kernel level. 
