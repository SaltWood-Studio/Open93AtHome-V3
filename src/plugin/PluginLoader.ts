import * as fs from 'fs';
import * as path from 'path';
import { Plugin } from './Plugin';
import { Server } from '../server';

export class PluginLoader {
    private plugins: Plugin[] = [];

    async loadPlugins(server: Server, directory: string = './plugins'): Promise<Plugin[]> {
        const files = fs.readdirSync(directory);

        for (const file of files) {
            const filePath = path.join(directory, file);

            if (file.endsWith('.ts') || file.endsWith('.js')) {
                try {
                    const module = await import(filePath);

                    for (const key in module) {
                        const Class = module[key];

                        if (this.isPluginClass(Class)) {
                            let instance: Plugin | null = null;

                            try {
                                instance = this.createInstance(Class);
                            } catch {
                                try {
                                    instance = this.createInstance(Class, server);
                                } catch {
                                    // Handle instantiation errors as needed
                                }
                            }

                            if (instance) {
                                this.plugins.push(instance);
                            }
                        }
                    }
                } catch {
                    // Handle module loading errors as needed
                }
            }
        }

        return this.plugins;
    }

    private isPluginClass(value: any): value is typeof Plugin {
        return typeof value === 'function' && value.prototype instanceof Plugin && value !== Plugin;
    }

    private createInstance(Class: any, server?: Server): Plugin {
        if (server) {
            return new Class(server);
        }
        return new Class();
    }
}