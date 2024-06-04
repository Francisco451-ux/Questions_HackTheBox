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

