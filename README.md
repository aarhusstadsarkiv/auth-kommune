# auth-kommune
Starlette authentication middlewares for Aarhus Kommune server applications.

## Tables

### Users

```postgresql
create table users
(
    id    varchar(7),
    name  text  not null,
    email text  not null,
    roles jsonb not null,
    primary key (id)
);
```

### Access Log

```postgresql
create table access_logs
(
    time           timestamptz not null,
    user_id        varchar(7)  not null,
    request_method varchar(7)  not null,
    path           varchar     not null,
    response       int         not null
);

create index idx_access_logs_user_id on access_logs (user_id);
```