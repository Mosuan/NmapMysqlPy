create database portscan;

use portscan;

create table port_list(
`id` int(11) not null AUTO_INCREMENT,
`ip` varchar(255) not null comment 'ip xx.xxx.xx.xx',
`port` int(10) not null comment '端口',
`version` varchar(255) comment '版本',
`name` varchar(255) comment '服务名 如http',
`status` int(1) not null DEFAULT 1 comment '状态',
`addtime` int(20) not null comment '添加时间',
`plugins_scan` int(1) not null DEFAULT 1 comment '默认1， 1未扫描，2已经扫描，3未知原因',
primary key (`id`)
)ENGINE=InnoDB DEFAULT CHARSET=utf8;