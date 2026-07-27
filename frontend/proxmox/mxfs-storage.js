/*
 * MXFS — Proxmox VE Storage Plugin Web UI
 *
 * Registers MXFS in the Datacenter -> Storage -> Add dropdown
 * and provides the configuration form panel.
 *
 * Installed to /usr/share/pve-manager/js/mxfs-storage.js
 * Loaded via <script> tag injected into index.html.tpl by postinst.
 */

/* Register MXFS in the storage schema so it appears in the Add dropdown */
PVE.Utils.storageSchema.mxfs = {
    name: 'MXFS',
    ipanel: 'MXFSInputPanel',
    faIcon: 'server',
    backups: true,
};

/* Input panel for Add/Edit MXFS storage dialog */
Ext.define('PVE.storage.MXFSInputPanel', {
    extend: 'PVE.panel.StorageBase',

    onGetValues: function(values) {
        var me = this;

        /* If no path specified, default to /mnt/pve/<id> */
        if (!values.path && values.storage) {
            values.path = '/mnt/pve/' + values.storage;
        }

        /* Don't send empty options string — API rejects it */
        if (values.options !== undefined && values.options.length === 0) {
            delete values.options;
        }

        return me.callParent([values]);
    },

    initComponent: function() {
        var me = this;

        me.column1 = [
            {
                xtype: me.isCreate ? 'textfield' : 'displayfield',
                name: 'blockdevice',
                value: '',
                fieldLabel: gettext('Block Device'),
                emptyText: '/dev/sdX',
                allowBlank: false,
            },
            {
                xtype: me.isCreate ? 'textfield' : 'displayfield',
                name: 'path',
                value: '',
                fieldLabel: gettext('Mount Point'),
                emptyText: '/mnt/pve/<id>',
                allowBlank: true,
            },
            {
                xtype: 'pveContentTypeSelector',
                name: 'content',
                value: 'images',
                multiSelect: true,
                fieldLabel: gettext('Content'),
                allowBlank: false,
            },
        ];

        me.column2 = [
            {
                xtype: 'proxmoxcheckbox',
                name: 'shared',
                checked: true,
                uncheckedValue: 0,
                fieldLabel: gettext('Shared'),
                autoEl: {
                    tag: 'div',
                    'data-qtip': gettext(
                        'MXFS is a shared cluster filesystem. Enable unless this storage is used on a single node only.'
                    ),
                },
            },
            {
                xtype: 'textfield',
                name: 'options',
                value: '',
                fieldLabel: gettext('Mount Options'),
                emptyText: gettext('none'),
                allowBlank: true,
            },
        ];

        me.callParent();
    },
});
