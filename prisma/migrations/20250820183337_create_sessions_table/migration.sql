-- CreateTable
CREATE TABLE "sessions" (
    "user_id" BIGINT NOT NULL,
    "device_id" TEXT NOT NULL,
    "device_name" TEXT NOT NULL,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("user_id","device_id")
);

-- CreateIndex
CREATE INDEX "sessions_device_id_user_id_idx" ON "sessions"("device_id", "user_id");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
