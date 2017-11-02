  ALTER TABLE comment auto_increment=1;

# comment 评论
insert into comment(content,movie_id,user_id,addtime) values("挺好看的",2, 9,now())
insert into comment(content,movie_id,user_id,addtime) values("还行",2, 19,now())
insert into comment(content,movie_id,user_id,addtime) values("不好看。。。",2, 5,now())
insert into comment(content,movie_id,user_id,addtime) values("已经第二次看啦",2, 7,now())
insert into comment(content,movie_id,user_id,addtime) values("挺好看的",2, 19,now())
insert into comment(content,movie_id,user_id,addtime) values("挺好看的",2, 19,now())


# moviecol 收藏
insert into moviecol(movie_id,user_id,addtime) values(3, 9,now())
insert into moviecol(movie_id,user_id,addtime) values(3, 11,now())



# 会员登录日志
insert into userlog(user_id,ip,addtime) values(1,"192.168.0.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.1.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.2.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.3.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.4.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.5.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.6.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.7.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.8.3",now());
insert into userlog(user_id,ip,addtime) values(1,"192.168.9.3",now());