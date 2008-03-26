#!/bin/sh -e

# Generate templates for the Snort packages
# This should be done whenever the templates are modified

for package in ""; do
    packagename=$package
    [ -n "$package" ] && packagename="-$packagename"
    OUTPUT="vyatta-snort$packagename.templates"
    echo "Generating templates for vyatta-snort$packagename at $OUTPUT"
    cat vyatta-snort.TEMPLATE.templates | sed -e "s/{PACKAGE}/$packagename/g" >$OUTPUT
    # Add Database templates also
    if [ "$package" = "mysql" ] || [ "$package" = "pgsql" ] ; then
        cat vyatta-snort.DATABASE.templates | sed -e "s/{PACKAGE}/$packagename/g" | sed -e "s/{DATABASE}/$package/g" >>$OUTPUT
    fi
            
    # Finally, add any additional templates this package might have
    if [ -e "vyatta-snort$packagename.ADD.templates" ] ; then
        cat "vyatta-snort$packagename.ADD.templates"  >>$OUTPUT
    fi
done

exit 0
