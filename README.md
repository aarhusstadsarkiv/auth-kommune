# auth-kommune

Starlette authentication middlewares for Aarhus Kommune server applications.

## Tables

### Users

```postgresql
create table users
(
    id              varchar(7),
    name            text  not null,
    email           text  not null,
    department      int,
    department_tree int[],
    roles           jsonb not null,
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
create index idx_access_logs_time on access_logs (time);
create index idx_access_logs_request on access_logs (request_method, path);
```


## Triggers

### Access Log

```postgresql
create function trig_access_logs_delete_duplicate() returns trigger
    language plpgsql as
$$
declare
    previous_time timestamptz;
begin
    select log.time
    into previous_time
    from access_logs log
    where log.user_id = new.user_id
      and log.path = new.path
      and log.request_method = new.request_method
      and log.path = new.path
      and log.response = new.response
    order by time desc
    limit 1;

    if previous_time is null then
        return new;
    elsif new.time - previous_time < interval '60 seconds' then
        return null;
    else
        return new;
    end if;
end;
$$;

create trigger trig_access_logs_delete_duplicate
    before insert
    on access_logs
    for each row
execute procedure trig_access_logs_delete_duplicate();
```