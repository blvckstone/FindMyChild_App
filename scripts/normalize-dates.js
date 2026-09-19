#!/usr/bin/env node
/**
 * One-off repair for child records whose date fields are not canonical ISO.
 *
 * The date search and date-range search compare `missingDate` with plain string operators, so
 * a value written as "15/07/2026" or "2026-07-15T10:30:00Z" is permanently invisible to them.
 * Every write now normalizes the value (functions/dates.js); this script fixes the rows that
 * were written before that.
 *
 *   node scripts/normalize-dates.js            # repair
 *   node scripts/normalize-dates.js --dry-run  # report only, change nothing
 *
 * Idempotent: rows that are already canonical are never touched, and unparsable values are
 * cleared to "" (never guessed) and counted in the summary.
 */
require('dotenv').config();
const mongoose = require('mongoose');
const fmcConnectMongoDB = require('../functions/fmcDB/fmcMongoDB');
const { migrateChildDates, isCanonicalYmd, isCanonicalTime } = require('../functions/dates');

const DRY_RUN = process.argv.includes('--dry-run');

const main = async () => {
    const connection = await fmcConnectMongoDB();
    if (!connection.success) {
        console.error('Database unavailable:', connection.message);
        process.exitCode = 1;
        return;
    }

    const Child = connection.data;

    if (DRY_RUN) {
        const docs = await Child.find({}).select('_id fullName missingDate missingTime').lean();
        const broken = docs.filter((doc) => !isCanonicalYmd(doc.missingDate) || !isCanonicalTime(doc.missingTime));
        console.log(`Dry run: ${broken.length} of ${docs.length} records need repair.`);
        for (const doc of broken.slice(0, 25)) {
            console.log(`  ${doc._id}  ${doc.fullName || '(no name)'}  missingDate=${JSON.stringify(doc.missingDate)}  missingTime=${JSON.stringify(doc.missingTime)}`);
        }
        if (broken.length > 25) console.log(`  ...and ${broken.length - 25} more`);
        return;
    }

    const summary = await migrateChildDates(Child);
    console.log('Date repair complete:', summary);
};

main()
    .catch((error) => {
        console.error('Date repair failed:', error.message);
        process.exitCode = 1;
    })
    .finally(async () => {
        await mongoose.disconnect().catch(() => {});
    });
