import { z } from "zod";
export const RequestPayloadSchema = z.object({
    url: z.string().url(),
    headers: z.record(z.string()).optional(),
});
