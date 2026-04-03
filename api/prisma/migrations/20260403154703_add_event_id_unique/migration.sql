/*
  Warnings:

  - Added the required column `event_id` to the `AuditLog` table without a default value. This is not possible if the table is not empty.

*/
-- DropIndex
DROP INDEX "audit_log_metadata_gin";

-- AlterTable
ALTER TABLE "AuditLog" ADD COLUMN     "event_id" TEXT NOT NULL;
