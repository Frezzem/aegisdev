import type { Ecosystem, TyposquatInfo } from "./types.js";

/**
 * A deliberately small set of high-traffic packages used for typosquat
 * detection. This is not a popularity database — it is only a comparison
 * baseline. New legitimate packages are protected by the download/age checks
 * in the risk engine, so a distance hit alone never blocks installation.
 */
export const POPULAR_NPM = [
  "accepts",
  "ajv",
  "axios",
  "bcrypt",
  "bcryptjs",
  "better-sqlite3",
  "body-parser",
  "chalk",
  "cheerio",
  "classnames",
  "commander",
  "cookie",
  "cors",
  "cross-env",
  "date-fns",
  "dayjs",
  "dotenv",
  "drizzle-orm",
  "electron",
  "eslint",
  "express",
  "fastify",
  "fs-extra",
  "glob",
  "helmet",
  "ioredis",
  "jest",
  "joi",
  "jsonwebtoken",
  "koa",
  "lodash",
  "marked",
  "mongoose",
  "morgan",
  "multer",
  "mysql2",
  "nanoid",
  "next",
  "node-fetch",
  "nodemailer",
  "npm",
  "openai",
  "ora",
  "pg",
  "pino",
  "playwright",
  "prettier",
  "prisma",
  "puppeteer",
  "react",
  "react-dom",
  "redis",
  "rimraf",
  "semver",
  "sequelize",
  "sharp",
  "socket.io",
  "sqlite3",
  "stripe",
  "tailwindcss",
  "ts-node",
  "tsx",
  "typescript",
  "undici",
  "uuid",
  "vite",
  "vitest",
  "webpack",
  "winston",
  "ws",
  "yargs",
  "zod",
  "zustand",
  "@anthropic-ai/sdk",
  "@aws-sdk/client-s3",
  "@langchain/core",
  "@modelcontextprotocol/sdk",
  "@nestjs/core",
  "@openai/sdk",
  "@prisma/client",
  "@tanstack/react-query",
  "@types/node",
  "@vitejs/plugin-react",
] as const;

export const POPULAR_PYPI = [
  "aiohttp",
  "alembic",
  "anthropic",
  "beautifulsoup4",
  "black",
  "boto3",
  "celery",
  "click",
  "cryptography",
  "django",
  "email-validator",
  "fastapi",
  "flask",
  "gradio",
  "gunicorn",
  "httpx",
  "jinja2",
  "langchain",
  "loguru",
  "matplotlib",
  "mypy",
  "numpy",
  "openai",
  "pandas",
  "passlib",
  "pillow",
  "pip",
  "playwright",
  "psycopg2-binary",
  "pydantic",
  "pyjwt",
  "pymongo",
  "pytest",
  "python-dotenv",
  "python-multipart",
  "pyyaml",
  "redis",
  "requests",
  "rich",
  "ruff",
  "scikit-learn",
  "scrapy",
  "seaborn",
  "selenium",
  "setuptools",
  "sqlalchemy",
  "starlette",
  "streamlit",
  "tensorflow",
  "torch",
  "tqdm",
  "transformers",
  "typer",
  "uvicorn",
  "uv",
  "poetry",
] as const;

export function popularFor(ecosystem: Ecosystem): readonly string[] {
  return ecosystem === "npm" ? POPULAR_NPM : POPULAR_PYPI;
}

export function findTyposquat(
  name: string,
  ecosystem: Ecosystem,
  candidates: readonly string[] = popularFor(ecosystem),
): TyposquatInfo | undefined {
  // Scoped packages have their own namespace; comparing the local name alone
  // would create false positives for @company/lodash.
  if (name.startsWith("@")) {
    return undefined;
  }
  const normalized = normalize(name);
  if (normalized.length < 4) {
    return undefined;
  }

  let best: TyposquatInfo | undefined;
  for (const candidate of candidates) {
    if (candidate.startsWith("@")) {
      continue;
    }
    const target = normalize(candidate);
    if (target === normalized) {
      return undefined;
    }
    const threshold = normalized.length >= 7 ? 2 : 1;
    const distance = damerauLevenshtein(normalized, target, threshold + 1);
    if (distance <= threshold && distance > 0) {
      if (!best || distance < best.distance) {
        best = { popularName: candidate, distance };
      }
    }
  }
  return best;
}

export function normalizePackageName(name: string): string {
  return normalize(name);
}

function normalize(name: string): string {
  return name.toLowerCase().replace(/[-_.]/g, "");
}

/**
 * Optimal string alignment distance with an early-exit band. A transposition
 * counts as one edit, which is how typosquatters usually operate.
 */
export function damerauLevenshtein(a: string, b: string, maxDistance = Infinity): number {
  if (a === b) {
    return 0;
  }
  if (Math.abs(a.length - b.length) > maxDistance) {
    return maxDistance + 1;
  }

  const rows = a.length + 1;
  const cols = b.length + 1;
  const matrix: number[][] = Array.from({ length: rows }, () => new Array<number>(cols).fill(0));

  for (let i = 0; i < rows; i += 1) {
    matrix[i]![0] = i;
  }
  for (let j = 0; j < cols; j += 1) {
    matrix[0]![j] = j;
  }

  for (let i = 1; i < rows; i += 1) {
    let rowMin = Number.POSITIVE_INFINITY;
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(
        matrix[i - 1]![j]! + 1,
        matrix[i]![j - 1]! + 1,
        matrix[i - 1]![j - 1]! + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        value = Math.min(value, matrix[i - 2]![j - 2]! + 1);
      }
      matrix[i]![j] = value;
      rowMin = Math.min(rowMin, value);
    }
    if (rowMin > maxDistance) {
      return maxDistance + 1;
    }
  }

  return matrix[a.length]![b.length]!;
}
