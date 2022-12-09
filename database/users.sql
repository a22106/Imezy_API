CREATE Table "users" (
    "id" serial primary key,
    "name" varchar(255) not null,
    "email" varchar(255) not null,
    "password" varchar(255) not null,
    "created_at" timestamp not null default now(),
    "updated_at" timestamp not null default now(),
    "is_active" boolean not null default true,
    "is_admin" boolean not null default false
);