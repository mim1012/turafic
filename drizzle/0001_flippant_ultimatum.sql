CREATE TYPE "public"."log_level" AS ENUM('info', 'warning', 'error');--> statement-breakpoint
CREATE TYPE "public"."task_status" AS ENUM('pending', 'running', 'completed', 'failed');--> statement-breakpoint
CREATE TABLE "naverCookies" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "naverCookies_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"nnb" varchar(255) NOT NULL,
	"nidAut" varchar(255),
	"nidSes" varchar(255),
	"nidJkl" varchar(255),
	"isActive" integer DEFAULT 1 NOT NULL,
	"lastUsedAt" timestamp,
	"createdAt" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "taskLogs" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "taskLogs_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"taskId" integer NOT NULL,
	"level" "log_level" DEFAULT 'info' NOT NULL,
	"message" text NOT NULL,
	"metadata" text,
	"createdAt" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tasks" (
	"id" integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY (sequence name "tasks_id_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 2147483647 START WITH 1 CACHE 1),
	"campaignId" integer NOT NULL,
	"keywordId" integer,
	"trafficId" integer,
	"uaChange" integer DEFAULT 1 NOT NULL,
	"cookieHomeMode" integer DEFAULT 1 NOT NULL,
	"shopHome" integer DEFAULT 1 NOT NULL,
	"useNid" integer DEFAULT 0 NOT NULL,
	"useImage" integer DEFAULT 1 NOT NULL,
	"workType" integer DEFAULT 3 NOT NULL,
	"randomClickCount" integer DEFAULT 2 NOT NULL,
	"workMore" integer DEFAULT 1 NOT NULL,
	"secFetchSiteMode" integer DEFAULT 1 NOT NULL,
	"lowDelay" integer DEFAULT 2 NOT NULL,
	"status" "task_status" DEFAULT 'pending' NOT NULL,
	"rank" integer,
	"errorMessage" text,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"updatedAt" timestamp DEFAULT now() NOT NULL
);
