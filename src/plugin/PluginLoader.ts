import * as fs from 'fs';
import * as path from 'path';
import { Plugin } from './Plugin';
import { Server } from '../server';

export class PluginLoader {
    private pluginInstances: Plugin[] = [];

    async loadPlugins(server: Server, pluginDir: string = './plugins'): Promise<Plugin[]> {
        const pluginFiles = fs.readdirSync(pluginDir);
        for (const file of pluginFiles) {
            const fullPath = path.join(pluginDir, file);

            // 只加载 .ts 或 .js 文件
            if (file.endsWith('.js')) {
                try {
                    const module = await import(path.resolve(fullPath));

                    for (const exportedKey in module) {
                        const ExportedClass = module[exportedKey];

                        if (this.isConcretePluginClass(ExportedClass)) {
                            let pluginInstance: Plugin | null = null;

                            try {
                                pluginInstance = new (ExportedClass as new () => Plugin)();
                            } catch (error) {
                                try {
                                    pluginInstance = new (ExportedClass as unknown as new (server: Server) => Plugin)(server);
                                } catch (error) {
                                    console.error(`Failed to instantiate plugin from ${file} with a Server parameter:`, error);
                                }
                            }

                            if (pluginInstance) {
                                this.pluginInstances.push(pluginInstance);
                            }
                        }
                    }
                } catch (err) {
                    console.error(`Failed to load plugin from ${file}:`, err);
                }
            }
        }

        return this.pluginInstances;
    }

    private isConcretePluginClass(obj: any): obj is typeof Plugin {
        return typeof obj === 'function' && obj.prototype instanceof Plugin && !Object.is(obj, Plugin);
    }
}
